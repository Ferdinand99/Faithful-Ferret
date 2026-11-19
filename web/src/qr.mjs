// QR codes for the emergency sheet and the secret key (spec Fase 1 § 6.1 and § 6.2). The
// code is made by Project Nayuki's QR Code generator (MIT, vendor/qrcodegen), which this file
// only calls. A QR code is not cryptography: it carries a text that the sheet also prints, and
// it is as secret as that text.
//
// The text is written as bytes (UTF-8) in the QR byte mode, at most 512 bytes, so the same
// bytes come back from any reader. The error correction is M unless a caller asks for another
// level. The code is drawn from `dark(x, y)`; the quiet zone (four modules of light) is the
// drawing's job.
//
// The vendored module is imported from /js/vendor/, where the build puts it (the same place
// from the page and from the sources, as the worker client is).
import qrcodegen from "../js/vendor/qrcodegen/qrcodegen.mjs";

/** The most bytes of text one code carries. */
export const MAX_QR_BYTES = 512;

const LEVELS = Object.freeze({
  L: qrcodegen.QrCode.Ecc.LOW,
  M: qrcodegen.QrCode.Ecc.MEDIUM,
  Q: qrcodegen.QrCode.Ecc.QUARTILE,
  H: qrcodegen.QrCode.Ecc.HIGH,
});

const encoder = new TextEncoder();

/**
 * The modules of the QR code for `text`: `size` modules to a side, and `dark(x, y)` is true for a
 * dark module (x to the right, y down, from 0) and false outside the square.
 * Throws `RangeError("qr_too_long")` for a text over 512 bytes and `TypeError` for a text that is
 * not a string or a level that is not L, M, Q or H.
 * @param {string} text
 * @param {{ ecc?: "L" | "M" | "Q" | "H" }} [options]
 * @returns {{ size: number, dark: (x: number, y: number) => boolean }}
 */
export function qrModules(text, { ecc = "M" } = {}) {
  if (typeof text !== "string") throw new TypeError("qr: the text is a string");
  if (!Object.hasOwn(LEVELS, ecc)) throw new TypeError("qr: the level is L, M, Q or H");
  const bytes = encoder.encode(text);
  if (bytes.length > MAX_QR_BYTES) throw new RangeError("qr_too_long");
  const code = qrcodegen.QrCode.encodeBinary(bytes, LEVELS[ecc]);
  const size = code.size;
  return {
    size,
    dark: (x, y) => Number.isInteger(x) && Number.isInteger(y) && x >= 0 && y >= 0 && x < size && y < size && code.getModule(x, y),
  };
}
