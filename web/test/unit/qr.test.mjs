// The QR code: what qrModules draws is read back by a decoder (jsQR, a dev dependency that is never in
// dist/), for the setup texts of the sheet up to the limit of 512 bytes, and a longer text is refused.
import assert from "node:assert/strict";
import { test } from "node:test";
import jsQR from "jsqr";
import { MAX_QR_BYTES, qrModules } from "../../src/qr.mjs";

const encoder = new TextEncoder();

/** The modules as an RGBA image: `scale` pixels to a module, a quiet zone of four modules, black on white. */
function render(code, scale = 4) {
  const quiet = 4;
  const side = (code.size + 2 * quiet) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < code.size; y += 1) {
    for (let x = 0; x < code.size; x += 1) {
      if (!code.dark(x, y)) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const at = ((y + quiet) * scale + dy) * side * 4 + ((x + quiet) * scale + dx) * 4;
          data[at] = data[at + 1] = data[at + 2] = 0;
        }
      }
    }
  }
  return { data, side };
}

/** The bytes a decoder reads from the code for `text`. */
function decode(text, options) {
  const { data, side } = render(qrModules(text, options));
  const result = jsQR(data, side, side, { inversionAttempts: "dontInvert" });
  assert.ok(result, `the decoder reads the code for ${text.length} characters`);
  return Uint8Array.from(result.binaryData);
}

/** A deterministic text of `bytes` bytes of the characters a setup text has. */
function setupText(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_:/.";
  let out = "FFSETUP1:https://vault.example.net:8443/";
  let state = 12345;
  while (out.length < bytes) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[state % alphabet.length];
  }
  return out.slice(0, bytes);
}

test("qr_round_trips_through_a_decoder_for_setup_texts_up_to_512_bytes", () => {
  for (const bytes of [1, 20, 60, 100, 150, 200, 300, 400, 512]) {
    const text = setupText(bytes);
    assert.equal(encoder.encode(text).length, Math.min(bytes, text.length));
    assert.deepEqual(decode(text), encoder.encode(text), `${bytes} bytes`);
  }
  // The same code from the same text, so a print and a screen agree.
  const a = qrModules(setupText(200));
  const b = qrModules(setupText(200));
  assert.equal(a.size, b.size);
  for (let y = 0; y < a.size; y += 1) for (let x = 0; x < a.size; x += 1) assert.equal(a.dark(x, y), b.dark(x, y));
  // Text that is not ASCII goes through as its UTF-8 bytes, up to the limit.
  for (const text of ["zæøåÆØÅ", "ø".repeat(256), "café € 100", "日本語😀"]) {
    const bytes = encoder.encode(text);
    assert.ok(bytes.length <= MAX_QR_BYTES);
    assert.deepEqual(decode(text), bytes);
  }
  // The other levels draw readable codes too, and a higher level is not smaller.
  const sizes = [];
  for (const ecc of ["L", "M", "Q", "H"]) {
    assert.deepEqual(decode(setupText(80), { ecc }), encoder.encode(setupText(80)), ecc);
    sizes.push(qrModules(setupText(80), { ecc }).size);
  }
  assert.deepEqual(sizes, [...sizes].sort((x, y) => x - y));
});

test("qr_has_a_size_that_fits_the_modules_and_no_dark_module_outside", () => {
  const code = qrModules("hello");
  assert.ok(code.size >= 21 && code.size <= 177 && (code.size - 21) % 4 === 0, "a QR size is 21 + 4 (version - 1)");
  for (const [x, y] of [[-1, 0], [0, -1], [code.size, 0], [0, code.size], [1.5, 2], [Number.NaN, 0], [1e9, 1e9]]) {
    assert.equal(code.dark(x, y), false);
  }
  // The finder pattern: dark corner modules at the three corners, light at the fourth.
  assert.equal(code.dark(0, 0), true);
  assert.equal(code.dark(code.size - 1, 0), true);
  assert.equal(code.dark(0, code.size - 1), true);
});

test("qr_refuses_text_over_512_bytes", () => {
  const limit = "a".repeat(512);
  assert.ok(qrModules(limit).size > 0);
  assert.throws(() => qrModules(`${limit}a`), (e) => e instanceof RangeError && e.message === "qr_too_long");
  // The limit is in bytes: 256 two-byte characters fit, 257 do not.
  assert.ok(qrModules("ø".repeat(256)).size > 0);
  assert.throws(() => qrModules("ø".repeat(257)), (e) => e instanceof RangeError && e.message === "qr_too_long");
  assert.throws(() => qrModules("😀".repeat(129)), RangeError);
  // Not a text, or a level that does not exist.
  for (const bad of [5, null, undefined, {}, new Uint8Array(3)]) assert.throws(() => qrModules(/** @type {any} */ (bad)), TypeError);
  for (const ecc of ["m", "X", "", "constructor", "__proto__", 1]) {
    assert.throws(() => qrModules("a", { ecc: /** @type {any} */ (ecc) }), TypeError, String(ecc));
  }
});
