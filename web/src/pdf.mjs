// A small PDF writer for the emergency sheet (spec Fase 1 § 6.1). PDF 1.7, A4, one
// standard font (Helvetica, WinAnsi), text and filled rectangles, nothing else: no
// compression, no JavaScript, no link, no form, no attachment, no outline and no
// metadata (no /Info, no XMP, no date, no producer, no file id), so the file says
// nothing about who made it or when, and a reader has nothing to run or follow.
//
// The secrets of the sheet pass through here as text. The byte buffers of the writer
// are kept so that `dispose()` and `wipe()` can zero them. A JavaScript string that the
// caller passed in, and the Blob that a download makes of the bytes, cannot be zeroed.

/** A4 in points. */
export const PAGE_WIDTH = 595.276;
export const PAGE_HEIGHT = 841.89;

/** WinAnsi (Windows-1252) bytes for the code points above 0x7F that the encoding defines. */
const WIN_ANSI_HIGH = new Map([
  [0x20ac, 0x80], [0x201a, 0x82], [0x0192, 0x83], [0x201e, 0x84], [0x2026, 0x85], [0x2020, 0x86],
  [0x2021, 0x87], [0x02c6, 0x88], [0x2030, 0x89], [0x0160, 0x8a], [0x2039, 0x8b], [0x0152, 0x8c],
  [0x017d, 0x8e], [0x2018, 0x91], [0x2019, 0x92], [0x201c, 0x93], [0x201d, 0x94], [0x2022, 0x95],
  [0x2013, 0x96], [0x2014, 0x97], [0x02dc, 0x98], [0x2122, 0x99], [0x0161, 0x9a], [0x203a, 0x9b],
  [0x0153, 0x9c], [0x017e, 0x9e], [0x0178, 0x9f],
]);

/**
 * The WinAnsi byte of a character, or -1 when WinAnsi has none (control characters, DEL and
 * everything outside Latin-1 and the table above).
 * @param {number} code a code point
 */
function winAnsi(code) {
  if (code >= 0x20 && code <= 0x7e) return code;
  if (code >= 0xa0 && code <= 0xff) return code;
  return WIN_ANSI_HIGH.get(code) ?? -1;
}

/** A growing byte buffer that can be zeroed. */
export class Sink {
  constructor() {
    /** @type {Uint8Array} */
    this.buf = new Uint8Array(512);
    this.length = 0;
  }

  /** @param {number} extra */
  #room(extra) {
    if (this.length + extra <= this.buf.length) return;
    const next = new Uint8Array(Math.max(this.buf.length * 2, this.length + extra));
    next.set(this.buf.subarray(0, this.length));
    this.buf.fill(0);
    this.buf = next;
  }

  /** @param {number} byte */
  byte(byte) {
    this.#room(1);
    this.buf[this.length++] = byte;
  }

  /** ASCII text (operators, numbers, names). @param {string} text */
  ascii(text) {
    this.#room(text.length);
    for (let i = 0; i < text.length; i += 1) this.buf[this.length++] = text.charCodeAt(i) & 0xff;
  }

  /** @param {Uint8Array} bytes */
  bytes(bytes) {
    this.#room(bytes.length);
    this.buf.set(bytes, this.length);
    this.length += bytes.length;
  }

  view() {
    return this.buf.subarray(0, this.length);
  }

  wipe() {
    this.buf.fill(0);
    this.length = 0;
  }
}

/**
 * A number in a content stream: at most three decimals, never an exponent.
 * @param {number} value
 */
function num(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.abs(value) > 1_000_000) {
    throw new TypeError("pdf_number");
  }
  const text = (Math.round(value * 1000) / 1000).toFixed(3).replace(/\.?0+$/, "");
  return text === "" || text === "-0" ? "0" : text;
}

/**
 * The WinAnsi bytes of `str`, or `TypeError("pdf_char")` for a character that WinAnsi lacks.
 * @param {string} str
 * @returns {number[]}
 */
function winAnsiBytes(str) {
  if (typeof str !== "string") throw new TypeError("pdf_char");
  /** @type {number[]} */
  const bytes = [];
  for (const ch of str) {
    const byte = winAnsi(/** @type {number} */ (ch.codePointAt(0)));
    if (byte < 0) throw new TypeError("pdf_char");
    bytes.push(byte);
  }
  return bytes;
}

/**
 * Writes WinAnsi bytes as a PDF literal string. A parenthesis and a backslash get a backslash,
 * and every byte above 0x7E is written as an octal escape, so the file stays ASCII there.
 * @param {Sink} sink
 * @param {number[]} bytes
 */
function literal(sink, bytes) {
  sink.byte(0x28);
  for (const byte of bytes) {
    if (byte === 0x28 || byte === 0x29 || byte === 0x5c) {
      sink.byte(0x5c);
      sink.byte(byte);
    } else if (byte > 0x7e) {
      sink.ascii(`\\${byte.toString(8).padStart(3, "0")}`);
    } else {
      sink.byte(byte);
    }
  }
  sink.byte(0x29);
}

/**
 * @typedef {object} PdfPage
 * @property {(x: number, y: number, size: number, str: string) => void} text the text at (x, y) in points from the lower left corner, in Helvetica; WinAnsi characters only, anything else is a `TypeError("pdf_char")`
 * @property {(x: number, y: number, w: number, h: number) => void} rect a black filled rectangle
 *
 * @typedef {object} PdfDocument
 * @property {() => PdfPage} page adds a page and returns it
 * @property {() => Uint8Array} bytes the file
 * @property {() => void} dispose zeroes the writer's own buffers; the document is not used afterwards
 */

/**
 * @param {{ makeSink?: () => Sink }} [options] makeSink makes every buffer of the writer; the tests pass one that keeps them, to see that they are zeroed
 * @returns {PdfDocument}
 */
export function createPdf({ makeSink = () => new Sink() } = {}) {
  /** @type {Sink[]} */
  const pages = [];
  let disposed = false;

  const alive = () => {
    if (disposed) throw new Error("pdf_disposed");
  };

  return {
    page() {
      alive();
      const sink = makeSink();
      pages.push(sink);
      return {
        text(x, y, size, str) {
          alive();
          if (typeof size !== "number" || !(size > 0) || size > 1000) throw new TypeError("pdf_number");
          // All checks run before anything is written, so a refused call leaves the page as it was.
          const bytes = winAnsiBytes(str);
          const head = `BT /F1 ${num(size)} Tf ${num(x)} ${num(y)} Td `;
          sink.ascii(head);
          literal(sink, bytes);
          sink.ascii(" Tj ET\n");
          bytes.fill(0);
        },
        rect(x, y, w, h) {
          alive();
          sink.ascii(`${num(x)} ${num(y)} ${num(w)} ${num(h)} re f\n`);
        },
      };
    },

    bytes() {
      alive();
      if (pages.length === 0) throw new Error("pdf_no_pages");
      const out = makeSink();
      /** @type {number[]} */
      const offsets = [];
      /** @param {number} id @param {(sink: Sink) => void} body */
      const object = (id, body) => {
        offsets[id] = out.length;
        out.ascii(`${id} 0 obj\n`);
        body(out);
        out.ascii("\nendobj\n");
      };

      out.ascii("%PDF-1.7\n");
      out.bytes(new Uint8Array([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a])); // binary marker comment
      object(1, (s) => s.ascii("<< /Type /Catalog /Pages 2 0 R >>"));
      const kids = pages.map((_, i) => `${4 + 2 * i} 0 R`).join(" ");
      object(2, (s) => s.ascii(`<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`));
      object(3, (s) => s.ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"));
      for (const [i, page] of pages.entries()) {
        object(4 + 2 * i, (s) =>
          s.ascii(
            `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${num(PAGE_WIDTH)} ${num(PAGE_HEIGHT)}] ` +
              `/Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + 2 * i} 0 R >>`,
          ),
        );
        object(5 + 2 * i, (s) => {
          s.ascii(`<< /Length ${page.length} >>\nstream\n`);
          s.bytes(page.view());
          s.ascii("\nendstream");
        });
      }
      const count = 4 + 2 * pages.length; // objects 0 .. count - 1
      const xref = out.length;
      out.ascii(`xref\n0 ${count}\n0000000000 65535 f \n`);
      for (let id = 1; id < count; id += 1) out.ascii(`${String(offsets[id]).padStart(10, "0")} 00000 n \n`);
      out.ascii(`trailer\n<< /Size ${count} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
      const bytes = out.view().slice();
      out.wipe();
      return bytes;
    },

    dispose() {
      for (const sink of pages) sink.wipe();
      pages.length = 0;
      disposed = true;
    },
  };
}

/**
 * Zeroes bytes that held a sheet (after the download or the print).
 * @param {Uint8Array} bytes
 */
export function wipe(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("pdf: wipe needs bytes");
  bytes.fill(0);
}
