// Helpers for the tests of the emergency sheet: the text of a PDF this writer made, the QR code
// read back from its rectangles, and the values of a sheet. Test-only values; none is a real key.
import assert from "node:assert/strict";
import jsQR from "jsqr";

export const SERVER_URL = "https://vault.example.net:8443";
export const EMAIL = "ada@example.test";
export const ACCOUNT_ID = "8a7d3c1e-5b2f-4e9a-9c64-1f0e2d3b4a59";
export const SK = "FFS1-TESTA-TESTB-TESTC-TESTD-TESTE-TESTF";
export const RK = "FFR1-ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789-ABCD-EFGH-JKMN-PQRS-TVWX-YZ01";
export const QR_TEXT =
  "ferret-setup:v1?u=https%3A%2F%2Fvault.example.net%3A8443&a=8a7d3c1e5b2f4e9a9c641f0e2d3b4a59&k=1&s=1&o=" + "ab".repeat(32);

/** A sheet as the core gives it, with the values above. */
export function sheet({ secretKey = SK, qr = QR_TEXT, server = SERVER_URL } = {}) {
  return {
    access: {
      server_url: server,
      email: EMAIL,
      account_id: ACCOUNT_ID,
      ksf_profile: 1,
      secret_key_code: secretKey,
      qr_payload: qr,
    },
    recoveryKeyCode: RK,
  };
}

const latin1 = (bytes) => Buffer.from(bytes).toString("latin1");

/** The content stream of every page of a file this writer made. */
export function streams(bytes) {
  return [...latin1(bytes).matchAll(/stream\n([\s\S]*?)\nendstream/g)].map((m) => m[1]);
}

/** The strings of a page's `(text) Tj`, in order, with the escapes of the writer undone. */
export function lines(stream) {
  return [...stream.matchAll(/\(((?:[^\\)]|\\.)*)\) Tj/g)].map((m) =>
    m[1].replace(/\\([0-7]{3}|.)/g, (_, c) => (c.length === 3 ? String.fromCharCode(Number.parseInt(c, 8)) : c)),
  );
}

/** The text of each page: its lines in order. */
export function pages(bytes) {
  return streams(bytes).map(lines);
}

/** The filled rectangles of a page: [x, y, w, h]. */
export function rects(stream) {
  return [...stream.matchAll(/^(\S+) (\S+) (\S+) (\S+) re f$/gm)].map((m) => m.slice(1, 5).map(Number));
}

/** The text a decoder reads from the rectangles of a page (the only rectangles on it are the QR code's). */
export function decodeQr(stream) {
  const all = rects(stream);
  assert.ok(all.length > 0, "the page has a QR code");
  const unit = Math.min(...all.map((r) => r[3]));
  const left = Math.min(...all.map((r) => r[0]));
  const bottom = Math.min(...all.map((r) => r[1]));
  const right = Math.max(...all.map((r) => r[0] + r[2]));
  const top = Math.max(...all.map((r) => r[1] + r[3]));
  // Four modules of quiet zone around the drawing, rendered at 6 pixels to a point.
  const scale = 6;
  const quiet = 4 * unit;
  const width = Math.ceil((right - left + 2 * quiet) * scale);
  const height = Math.ceil((top - bottom + 2 * quiet) * scale);
  const data = new Uint8ClampedArray(width * height * 4).fill(255);
  for (const [x, y, w, h] of all) {
    const x0 = Math.round((x - left + quiet) * scale);
    const x1 = Math.round((x - left + w + quiet) * scale);
    const y0 = Math.round((top - (y + h) + quiet) * scale);
    const y1 = Math.round((top - y + quiet) * scale);
    for (let py = y0; py < y1; py += 1) {
      for (let px = x0; px < x1; px += 1) {
        const at = (py * width + px) * 4;
        data[at] = data[at + 1] = data[at + 2] = 0;
      }
    }
  }
  const result = jsQR(data, width, height, { inversionAttempts: "dontInvert" });
  assert.ok(result, "the decoder reads the QR code of the page");
  return Buffer.from(result.binaryData).toString("utf8");
}
