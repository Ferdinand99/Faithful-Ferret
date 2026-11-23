// One-time codes for the tests (RFC 6238 with its defaults: HMAC-SHA1, 6 digits, 30 seconds), so the matrix can tell
// where a fill put the code of an entry whose secret the run made up. Test code only; the extension takes its codes
// from the core.
import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 without padding. @param {Uint8Array} bytes */
export function base32(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** @param {string} text */
function fromBase32(text) {
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const char of text.toUpperCase()) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error("not base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * The code of a secret for one 30-second step.
 * @param {string} secret base32 @param {number} step
 */
export function totpAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", fromBase32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}

/**
 * The codes a fill around `nowMs` can have put into a page: the step before, the step of `nowMs` and the one after.
 * @param {string} secret base32 @param {number} [nowMs]
 */
export function recentCodes(secret, nowMs = Date.now()) {
  const step = Math.floor(nowMs / 30_000);
  return [step - 1, step, step + 1].map((s) => totpAt(secret, s));
}
