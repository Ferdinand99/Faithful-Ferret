// Helpers for the one-time password tests: a reference TOTP (RFC 4226 and RFC 6238, written here from the RFCs and checked against
// their published vectors in totpModel.test.mjs, so it is an oracle that does not depend on the code under test) and a fake worker
// client that answers `totp_parse`, `totp_code`, `reveal_totp_secret` and the throwaway item of the form's preview the way the
// core does, with that reference. Every secret here is a test value.
import { createHmac } from "node:crypto";
import { fakeClient } from "./vaultHelpers.mjs";

/** The RFC 6238 test secret (the ASCII bytes of "12345678901234567890") in Base32. */
export const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/** The same secret as an address. */
export const RFC_URI = `otpauth://totp/Example:ada?secret=${RFC_SECRET}&issuer=Example`;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** @param {string} text Base32 (any case, spaces, `=` fill) @returns {Buffer} */
export function base32(text) {
  const clean = text.replace(/\s+/g, "").replace(/=+$/, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    const at = ALPHABET.indexOf(ch);
    if (at < 0) throw new Error("not base32");
    bits += at.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** @param {Uint8Array} bytes Base32 without fill */
export function encodeBase32(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += ALPHABET[Number.parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}

/**
 * The code of RFC 6238 for a secret, the way an authenticator app makes it.
 * @param {{ secret: string, algorithm?: string, digits?: number, period?: number }} params
 * @param {number} seconds Unix time
 */
export function reference({ secret, algorithm = "SHA1", digits = 6, period = 30 }, seconds) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / period)));
  const mac = createHmac(algorithm.toLowerCase(), base32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const number = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 10 ** digits).padStart(digits, "0");
}

const refuse = () => Object.assign(new Error("malformed_otpauth"), { code: "malformed_otpauth" });

/**
 * What the core's strict parser says about an address (the part the tests need: scheme and type exactly, the allow-listed
 * parameters once each, a Base32 secret).
 * @param {string} text
 */
export function parseUri(text) {
  const uri = String(text).trim();
  const match = /^otpauth:\/\/totp\/([^?#]*)\?([^#]*)$/.exec(uri);
  if (!match) throw refuse();
  const params = new Map();
  for (const pair of match[2].split("&")) {
    const at = pair.indexOf("=");
    if (at < 1) throw refuse();
    const key = pair.slice(0, at);
    if (!["secret", "issuer", "algorithm", "digits", "period"].includes(key) || params.has(key)) throw refuse();
    params.set(key, decodeURIComponent(pair.slice(at + 1).replace(/\+/g, " ")));
  }
  const secret = params.get("secret") ?? "";
  if (secret === "" || !/^[A-Za-z2-7 ]+=*$/.test(secret)) throw refuse();
  const algorithm = (params.get("algorithm") ?? "SHA1").toUpperCase();
  if (!["SHA1", "SHA256", "SHA512"].includes(algorithm)) throw refuse();
  const digits = Number(params.get("digits") ?? 6);
  const period = Number(params.get("period") ?? 30);
  if (!Number.isInteger(digits) || digits < 6 || digits > 8 || !Number.isInteger(period) || period < 1 || period > 120) throw refuse();
  const full = decodeURIComponent(match[1]);
  const colon = full.indexOf(":");
  const labelIssuer = colon >= 0 ? full.slice(0, colon).trim() : null;
  const label = (colon >= 0 ? full.slice(colon + 1) : full).trim();
  const issuer = (params.get("issuer") ?? "").trim() || labelIssuer;
  return { secret: secret.replace(/\s+/g, ""), algorithm, digits, period, issuer, label };
}

/**
 * The worker client of the item and edit screens with the one-time password calls. `uris` maps an item id to its stored address.
 * Every call is in `client.calls`, as for `fakeClient`. A throwaway item sealed for the form's preview is kept in memory only
 * (`client.sealed`), the way the real one lives in the worker.
 * @param {ReturnType<typeof import("./vaultHelpers.mjs").fakeEngine>} engine
 * @param {{ uris?: Record<string, string>, notes?: Record<string, string> }} [options]
 */
export function fakeTotpClient(engine, { uris = {}, notes = {} } = {}) {
  const client = fakeClient(engine, { notes });
  /** @type {Map<string, string>} */
  const sealed = new Map();
  /** @type {Map<number, string>} */
  const previews = new Map();
  let next = 5000;
  const handleUri = (/** @type {number} */ handle) => {
    const id = engine.handles.get(handle);
    const uri = id === undefined ? previews.get(handle) : uris[id];
    if (uri === undefined) throw Object.assign(new Error("invalid_handle"), { code: id === undefined ? "invalid_handle" : "invalid_input" });
    return uri;
  };
  Object.assign(client, { sealed, previews });
  Object.assign(client.vault, {
    async totp_parse(/** @type {string} */ uri) {
      client.calls.push(["totp_parse", uri]);
      const { algorithm, digits, period, issuer, label } = parseUri(uri);
      return { algorithm, digits, period, issuer, label };
    },
    async totp_code(/** @type {number} */ handle, /** @type {number} */ seconds) {
      client.calls.push(["totp_code", handle, seconds]);
      if (!Number.isFinite(seconds) || seconds < 0) throw Object.assign(new Error("invalid_input"), { code: "invalid_input" });
      const params = parseUri(handleUri(handle));
      const code = reference(params, seconds);
      return { code, seconds_left: params.period - (Math.floor(seconds) % params.period) };
    },
    async reveal_totp_secret(/** @type {number} */ handle) {
      client.calls.push(["reveal_totp_secret", handle]);
      return handleUri(handle);
    },
    async encrypt_item(/** @type {Uint8Array} */ id, /** @type {number} */ rev, /** @type {any} */ draft) {
      client.calls.push(["encrypt_item", rev, structuredClone(draft)]);
      const uri = String(draft?.totp?.uri ?? "");
      parseUri(uri);
      const key = Buffer.from(id).toString("hex");
      sealed.set(key, uri);
      return { rev, envelope: new Uint8Array([1, 2, 3]), tag: new Uint8Array(16), key };
    },
    async open_item(/** @type {Uint8Array} */ id) {
      client.calls.push(["open_item"]);
      const uri = sealed.get(Buffer.from(id).toString("hex"));
      if (uri === undefined) throw Object.assign(new Error("not_found"), { code: "not_found" });
      next += 1;
      previews.set(next, uri);
      return next;
    },
    async close_item(/** @type {number} */ handle) {
      client.calls.push(["close_item", handle]);
      previews.delete(handle);
    },
  });
  return client;
}

/** The text of every attribute and every text node and every `value` below `root`, for a search for a secret. */
export function everything(/** @type {any} */ root) {
  const out = [];
  const visit = (/** @type {any} */ node) => {
    if (typeof node.data === "string") out.push(node.data);
    if (typeof node.value === "string") out.push(node.value);
    if (node.attributes instanceof Map) for (const [name, value] of node.attributes) out.push(name, value);
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(root);
  return out.join("\n");
}
