// The two text encodings of the wire: strict base64url without padding for
// bytes, and 32 lower-case hex characters for the 16-byte ids. Both refuse
// everything else (padding, the standard alphabet, whitespace, upper case,
// spare bits), so one byte string has exactly one text and the server and the
// vault read the same thing. No dependency, and no `Buffer`: this runs in the
// browser.

/** A wire value that is not in the one accepted form. `code` is a code of the server's error list. */
export class WireError extends Error {
  /**
   * @param {string} message
   * @param {string} [code]
   */
  constructor(message, code = "bad_request") {
    super(`${code}: ${message}`);
    this.name = "WireError";
    /** @type {string} */
    this.code = code;
  }
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i += 1) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export const b64u = Object.freeze({
  /**
   * @param {Uint8Array} bytes
   * @returns {string}
   */
  encode(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("b64u.encode needs a Uint8Array");
    let out = "";
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
    }
    const left = bytes.length - i;
    if (left === 1) {
      const n = bytes[i] << 16;
      out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63];
    } else if (left === 2) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63];
    }
    return out;
  },

  /**
   * Strict: only the URL-safe alphabet, no padding, no whitespace, and the
   * spare bits of the last character must be zero.
   * @param {unknown} text
   * @param {string} [code] the error code to refuse with
   * @returns {Uint8Array}
   */
  decode(text, code = "bad_request") {
    if (typeof text !== "string") throw new WireError("not a string", code);
    const n = text.length;
    if (n % 4 === 1) throw new WireError("not base64url", code);
    const out = new Uint8Array(Math.floor((n * 3) / 4));
    let acc = 0;
    let bits = 0;
    let at = 0;
    for (let i = 0; i < n; i += 1) {
      const c = text.charCodeAt(i);
      const v = c < 128 ? LOOKUP[c] : -1;
      if (v < 0) throw new WireError("not base64url", code);
      acc = (acc << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[at] = (acc >> bits) & 0xff;
        at += 1;
        acc &= (1 << bits) - 1;
      }
    }
    if (acc !== 0) throw new WireError("not canonical base64url", code);
    return out;
  },
});

const HEX = "0123456789abcdef";

export const hex16 = Object.freeze({
  /**
   * @param {Uint8Array} bytes exactly 16 bytes
   * @returns {string} 32 lower-case hex characters
   */
  encode(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
      throw new TypeError("hex16.encode needs 16 bytes");
    }
    let out = "";
    for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 15];
    return out;
  },

  /**
   * @param {unknown} text
   * @param {string} [code]
   * @returns {Uint8Array} 16 bytes
   */
  decode(text, code = "bad_request") {
    if (typeof text !== "string" || !/^[0-9a-f]{32}$/.test(text)) throw new WireError("not an id", code);
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    return out;
  },

  /**
   * Whether `text` is an id (32 lower-case hex characters).
   * @param {unknown} text
   * @returns {text is string}
   */
  is(text) {
    return typeof text === "string" && /^[0-9a-f]{32}$/.test(text);
  },
});
