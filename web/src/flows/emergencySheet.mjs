// The emergency sheet as a PDF (spec Fase 1 § 6.1, F-21). Made here in the page, from the text
// the core gave for the sheet; nothing is sent anywhere. Two pages:
//   page 1  server address, e-mail, account id, profile, the secret key (if the account has
//           one), the QR code of the setup text and the setup text itself;
//   page 2  the recovery key alone, with the text that says it opens the vault on its own and
//           is kept apart from page 1.
// Both pages say that recovery on a new browser needs both of them. A sheet with only page 2
// (`access: null`) is a renewed recovery key or a sheet whose page 1 could not be made.
//
// What the sheet holds is recovery material. This file keeps no state, logs nothing and
// reports a refusal as a fixed code. The writer's buffers are zeroed before the bytes are
// returned; the bytes themselves are the caller's to wipe (`wipe()` of pdf.mjs). A JavaScript
// string cannot be zeroed, and neither can the copy a download makes (see pdf.mjs).
import { createPdf, PAGE_HEIGHT, PAGE_WIDTH } from "../pdf.mjs";
import { MAX_QR_BYTES, qrModules } from "../qr.mjs";

/** @typedef {(key: string, vars?: Record<string, string | number>) => string} Translate */
/**
 * @typedef {object} AccessPage
 * @property {string} server_url
 * @property {string} email
 * @property {string} account_id
 * @property {number | string} ksf_profile
 * @property {string | null} [secret_key_code]
 * @property {string} [qr_payload]
 *
 * @typedef {object} Sheet
 * @property {AccessPage | null} access page 1; null for a sheet that has page 2 only
 * @property {string} recoveryKeyCode page 2
 */

const MARGIN = 56;
const WIDTH = PAGE_WIDTH - 2 * MARGIN;
const TOP = PAGE_HEIGHT - MARGIN;
/** Average width of a character of prose in Helvetica, in em; wide on purpose, so a line never leaves the page. */
const PROSE_EM = 0.58;
/** The widest glyph of a code or an address (W, %, m), in em: the characters per line are counted with it. */
const CODE_EM = 0.95;
/** The side of the QR code, at most, in points, and the widest a single module is drawn. */
const QR_SIDE = 220;
const QR_MODULE = 4;
const QUIET = 4;

/**
 * Whether the address of the server is anything but https. A sheet for such a server gets a
 * warning on the screen and before the file is saved: a cleartext address (even on localhost) is
 * what a new device would pin.
 * @param {unknown} serverUrl
 */
export function httpWarning(serverUrl) {
  return !(typeof serverUrl === "string" && /^https:\/\//i.test(serverUrl));
}

/**
 * Whether the QR text says that the account has a secret key (`s=1`) or not (`s=0`); null when it is not a
 * setup text of the frozen format or has no such bit.
 * @param {string | undefined} payload
 * @returns {boolean | null}
 */
function qrSecretKeyBit(payload) {
  const found = typeof payload === "string" && payload.startsWith("ferret-setup:v1?") ? /[?&]s=([01])(?:&|$)/.exec(payload) : null;
  return found === null ? null : found[1] === "1";
}

const encoder = new TextEncoder();

/**
 * Whether the setup text fits in one QR code (at most 512 bytes). A core address can be long enough that
 * its text does not; that is shown, never left out quietly.
 * @param {unknown} payload
 */
export function qrFits(payload) {
  return typeof payload === "string" && encoder.encode(payload).length <= MAX_QR_BYTES;
}

/**
 * The refusal for a page 1 that would carry a QR code for an account with a secret key and no secret
 * key, or the other way round. Page 1 is never made from such a sheet.
 * @param {AccessPage} access
 * @param {boolean | null} [expected] what the caller knows: whether the account uses a secret key
 */
export function checkAccessPage(access, expected = null) {
  if (typeof access.qr_payload !== "string" || access.qr_payload === "") throw new Error("sheet_qr_missing");
  const has = typeof access.secret_key_code === "string" && access.secret_key_code !== "";
  const bit = qrSecretKeyBit(access.qr_payload);
  // The frozen `s=` bit has to be there: the guard does not rest on a text of another shape.
  if (bit === null) throw new Error("sheet_qr_malformed");
  if (bit !== has || (expected !== null && expected !== has)) throw new Error("sheet_secret_key_mismatch");
}

/**
 * A value that goes on the sheet: ASCII only (a character the sheet cannot show the same way on every
 * printer is a mistake, not something to replace), printable.
 * @param {unknown} value
 * @returns {string}
 */
function ascii(value) {
  if (typeof value !== "string" || !/^[\x20-\x7e]*$/.test(value)) throw new TypeError("sheet_non_ascii");
  return value;
}

/**
 * Lines of prose that fit the width.
 * @param {string} text
 * @param {number} size
 * @returns {string[]}
 */
function words(text, size) {
  const per = Math.max(10, Math.floor(WIDTH / (PROSE_EM * size)));
  /** @type {string[]} */
  const lines = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (word === "") continue;
    if (line !== "" && line.length + 1 + word.length > per) {
      lines.push(line);
      line = word;
    } else {
      line = line === "" ? word : `${line} ${word}`;
    }
  }
  if (line !== "") lines.push(line);
  return lines;
}

/**
 * A code cut into lines at its hyphens (the hyphen stays at the end of the line, so the lines read
 * back as the code).
 * @param {string} code
 * @param {number} size
 * @returns {string[]}
 */
function codeLines(code, size) {
  const per = Math.max(8, Math.floor(WIDTH / (CODE_EM * size)));
  const pieces = code.split("-");
  /** @type {string[]} */
  const lines = [];
  let line = "";
  for (const [i, piece] of pieces.entries()) {
    const part = i < pieces.length - 1 ? `${piece}-` : piece;
    if (line !== "" && line.length + part.length > per) {
      lines.push(line);
      line = part;
    } else {
      line += part;
    }
  }
  if (line !== "") lines.push(line);
  return lines;
}

/**
 * Text cut at a fixed number of characters (an address or the QR text has no hyphens to cut at).
 * @param {string} text
 * @param {number} size
 * @returns {string[]}
 */
function chunks(text, size) {
  const per = Math.max(8, Math.floor(WIDTH / (CODE_EM * size)));
  /** @type {string[]} */
  const lines = [];
  for (let i = 0; i < text.length; i += per) lines.push(text.slice(i, i + per));
  return lines.length === 0 ? [""] : lines;
}

/**
 * A cursor that writes down the page.
 * @param {import("../pdf.mjs").PdfPage} page
 */
function writer(page) {
  let y = TOP;
  const guard = () => {
    if (y < MARGIN) throw new Error("sheet_too_long");
  };
  return {
    /** @param {number} extra */
    skip(extra) {
      y -= extra;
    },
    /** @param {string[]} lines @param {number} size @param {number} leading */
    lines(lines, size, leading) {
      for (const line of lines) {
        y -= leading;
        guard();
        page.text(MARGIN, y, size, line);
      }
    },
    /** @param {number} height @returns {number} the y of the lower edge */
    reserve(height) {
      y -= height;
      guard();
      return y;
    },
    /** The place where the next line goes. */
    get y() {
      return y;
    },
  };
}

/**
 * The QR code as dark rectangles (a row's run of dark modules is one rectangle).
 * @param {import("../pdf.mjs").PdfPage} page
 * @param {{ size: number, dark: (x: number, y: number) => boolean }} code
 * @param {number} left
 * @param {number} bottom the lower edge of the code, quiet zone included
 * @param {number} unit the side of a module in points
 */
function drawQr(page, code, left, bottom, unit) {
  const total = (code.size + 2 * QUIET) * unit;
  for (let row = 0; row < code.size; row += 1) {
    let column = 0;
    while (column < code.size) {
      if (!code.dark(column, row)) {
        column += 1;
        continue;
      }
      let end = column;
      while (end < code.size && code.dark(end, row)) end += 1;
      page.rect(left + (QUIET + column) * unit, bottom + total - (QUIET + row + 1) * unit, (end - column) * unit, unit);
      column = end;
    }
  }
}

/**
 * Page 1.
 * @param {import("../pdf.mjs").PdfDocument} pdf
 * @param {AccessPage} access
 * @param {Translate} t
 */
function pageOne(pdf, access, t) {
  checkAccessPage(access);
  const page = pdf.page();
  const w = writer(page);
  w.lines([t("sheet.pdf.title_access")], 18, 18);
  w.skip(8);
  w.lines(words(t("sheet.new_browser"), 10), 10, 13);
  w.skip(10);
  /** @param {string} label @param {string[]} lines @param {number} size */
  const field = (label, lines, size) => {
    w.lines([label], 9, 12);
    w.lines(lines, size, size + 4);
    w.skip(8);
  };
  field(t("sheet.server"), chunks(ascii(access.server_url), 12), 12);
  field(t("sheet.email"), chunks(ascii(access.email), 12), 12);
  field(t("sheet.account_id"), [ascii(access.account_id)], 12);
  field(t("sheet.profile"), [ascii(String(access.ksf_profile))], 12);
  if (typeof access.secret_key_code === "string" && access.secret_key_code !== "") field(t("sheet.secret_key"), codeLines(ascii(access.secret_key_code), 14), 14);

  const payload = ascii(/** @type {string} */ (access.qr_payload));
  if (!qrFits(payload)) throw new RangeError("qr_too_long");
  const code = qrModules(payload);
  const unit = Math.min(QR_MODULE, QR_SIDE / (code.size + 2 * QUIET));
  w.lines([t("sheet.pdf.qr")], 9, 12);
  const bottom = w.reserve((code.size + 2 * QUIET) * unit + 4);
  drawQr(page, code, MARGIN, bottom, unit);
  w.skip(8);
  field(t("sheet.pdf.qr_text"), chunks(payload, 8), 8);
}

/**
 * Page 2.
 * @param {import("../pdf.mjs").PdfDocument} pdf
 * @param {string} recoveryKeyCode
 * @param {Translate} t
 */
function pageTwo(pdf, recoveryKeyCode, t) {
  const page = pdf.page();
  const w = writer(page);
  w.lines([t("sheet.pdf.title_recovery")], 18, 18);
  w.skip(8);
  w.lines(words(t("sheet.recovery_note"), 11), 11, 14);
  w.skip(6);
  w.lines(words(t("sheet.new_browser"), 10), 10, 13);
  w.skip(14);
  w.lines([t("sheet.recovery_key")], 9, 12);
  w.lines(codeLines(ascii(recoveryKeyCode), 16), 16, 22);
}

/**
 * @param {(pdf: import("../pdf.mjs").PdfDocument) => void} build
 * @returns {Uint8Array}
 */
function make(build) {
  const pdf = createPdf();
  try {
    build(pdf);
    return pdf.bytes();
  } finally {
    // The writer's own buffers are zeroed on every path, also when a page was refused half way.
    pdf.dispose();
  }
}

/**
 * The sheet as a PDF: page 1 (access, secret key and QR) and page 2 (the recovery key), or page 2
 * alone when `sheet.access` is null. The caller wipes the bytes after the download or the print.
 * @param {{ sheet: Sheet, t: Translate }} args
 * @returns {Uint8Array}
 */
export function sheetPdf({ sheet, t }) {
  return make((pdf) => {
    if (sheet.access !== null && sheet.access !== undefined) pageOne(pdf, sheet.access, t);
    pageTwo(pdf, sheet.recoveryKeyCode, t);
  });
}

/**
 * Page 1 alone, for a reprint of the access sheet.
 * @param {{ access: AccessPage, t: Translate }} args
 * @returns {Uint8Array}
 */
export function accessPdf({ access, t }) {
  return make((pdf) => pageOne(pdf, access, t));
}

/**
 * What a sheet with only page 2 is made of, for a caller that could not get page 1 (the core refuses
 * the full sheet when the account has a secret key and this device holds none) or does not need it
 * (a renewed recovery key). Never a page 1 with an empty secret key.
 * @param {string} recoveryKeyCode
 * @returns {Sheet}
 */
export function pageTwoOnly(recoveryKeyCode) {
  return { access: null, recoveryKeyCode };
}
