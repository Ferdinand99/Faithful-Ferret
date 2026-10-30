// Looks for secrets in the messages that the page's spies recorded.
//
// The same search as tests/node/secrets.test.mjs: a byte value (any
// TypedArray, ArrayBuffer, DataView or array of byte numbers; the page has
// flattened them into `hex` leaves) may not contain any run of 16 bytes of a
// secret, and a text may not contain such a run as hex (any case), base64 or
// base64url (at any of the three alignments). A secret shorter than 16 bytes
// is searched whole.

const WINDOW = 16;

/** Every run of 16 bytes of a secret (the secret itself when it is shorter). */
export function windows(secret) {
  if (secret.length <= WINDOW) return [secret];
  const out = [];
  for (let i = 0; i + WINDOW <= secret.length; i++) out.push(secret.subarray(i, i + WINDOW));
  return out;
}

/**
 * The texts in which a run of bytes shows: hex (compared in lower case) and
 * base64 / base64url as it looks at each of the three alignments. The
 * characters at the ends that depend on bytes next to the run are cut.
 */
function needles(window) {
  const b64 = [];
  for (let shift = 0; shift < 3; shift++) {
    const text = Buffer.concat([Buffer.alloc(shift), Buffer.from(window)]).toString("base64").replace(/=+$/, "");
    const cut = text.slice(Math.ceil((8 * shift) / 6), text.length - 2);
    b64.push(cut, cut.replace(/\+/g, "-").replace(/\//g, "_"));
  }
  return { hex: Buffer.from(window).toString("hex"), b64 };
}

/** A secret, prepared for the search. */
export function prepare(name, hex) {
  const bytes = Buffer.from(hex, "hex");
  if (bytes.length < WINDOW || bytes.every((b) => b === 0)) {
    throw new Error(`${name} does not look like a key`);
  }
  const runs = windows(bytes).map((w) => Buffer.from(w));
  return { name, bytes, runs, needles: runs.map(needles) };
}

function bytesHold(haystack, secret) {
  return secret.runs.some((run) => haystack.includes(run));
}

function textHolds(text, secret) {
  const lower = text.toLowerCase();
  return secret.needles.some((n) => lower.includes(n.hex) || n.b64.some((x) => x.length >= 12 && text.includes(x)));
}

/** The names of the secrets that a leaf holds. */
export function secretsIn(leaf, prepared) {
  const found = [];
  if (leaf.hex !== undefined) {
    const bytes = Buffer.from(leaf.hex, "hex");
    for (const s of prepared) if (bytesHold(bytes, s)) found.push(s.name);
  } else {
    for (const s of prepared) if (textHolds(leaf.text, s)) found.push(s.name);
  }
  return found;
}

/**
 * Every place where a message holds a secret.
 *
 * @param messages `{ worker, dir, method, leaves }` as the spies recorded them
 * @param secrets  `{ name: hex }`
 * @param allowed  `(message, secretName) => boolean`, the narrow exceptions
 */
export function findLeaks(messages, secrets, allowed = () => false) {
  const prepared = Object.entries(secrets).map(([name, hex]) => prepare(name, hex));
  const leaks = [];
  messages.forEach((message, index) => {
    for (const leaf of message.leaves) {
      for (const name of secretsIn(leaf, prepared)) {
        if (!allowed(message, name)) {
          leaks.push({ index, worker: message.worker, dir: message.dir, method: message.method, path: leaf.path, secret: name });
        }
      }
    }
  });
  return leaks;
}

// ------------------------------------------------------------- text secrets

/** A code as the user types it: separators dropped, upper case. */
const squash = (text) => text.replace(/[-\s]/g, "").toUpperCase();

/**
 * Every place where a message holds a code (a recovery or secret key as the
 * `FFR1-...` / `FFS1-...` text) as written, with or without its separators,
 * in a string or as UTF-8 in a byte value. These are values that a
 * `reveal_*` method hands out and that the user types back, so the caller
 * names the few places where they may sit.
 *
 * @param texts   `{ name: code }`
 * @param allowed `(message, name) => boolean`
 */
export function findTextLeaks(messages, texts, allowed = () => false) {
  const needles = Object.entries(texts).map(([name, code]) => [name, squash(code)]);
  const leaks = [];
  messages.forEach((message, index) => {
    for (const leaf of message.leaves) {
      const haystack = squash(leaf.hex !== undefined ? Buffer.from(leaf.hex, "hex").toString("utf8") : leaf.text);
      for (const [name, needle] of needles) {
        if (haystack.includes(needle) && !allowed(message, name)) {
          leaks.push({ index, worker: message.worker, dir: message.dir, method: message.method, path: leaf.path, secret: name });
        }
      }
    }
  });
  return leaks;
}
